package logparse;

import java.io.*;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.*;

/**
 * Detect mimikatz comparing Common DLL List with exported Sysmon event log.
 * Output processes that load all DLLs in Common DLL List and detection rate.
 * 
 * @version 1.0
 * @author Mariko Fujimoto
 */
public class SysmonDetecter_ML {

	 /**
	 * Specify file name of mimikatz
	 */
	//private static final String MIMIKATZ_MODULE_NAME = "HTran.exe";
	//private static final String MIMIKATZ_MODULE_NAME = "mimikatz.exe";
	private static final String MIMIKATZ_MODULE_NAME = "caidao.exe";
	
	private static Map<Integer, LinkedHashSet> log;
	private static Map<Integer, LinkedHashSet> image;
	private static LinkedHashSet<String> commonDLLlist = new LinkedHashSet<String>();
	private static String commonDLLlistFileName = null;
	private static String outputDirName = null;
	private static int falsePositiveCnt = 0;
	private static int falseNegativeCnt = 0;
	
	private int totalProcessCnt=0;
	private int processCntMimi=0;
	private int detectedProcessCntMimi=0;
	
	private static boolean detectByExeName=false;
	
	private void readCSV(String filename) {

		try {
			File f = new File(filename);
			BufferedReader br = new BufferedReader(new FileReader(f));
			String line;
			int processId = 0;
			String date="";
			String image="";
			String imageLoaded ="";
			
			while ((line = br.readLine()) != null) {
				String[] data = line.split(",", 0);
				for (String elem : data) {
					if (elem.startsWith("情報") || elem.startsWith("Information")) {
						  date = data[1];
					} else if (elem.startsWith("ProcessId:")) {
						processId = Integer.parseInt(parseElement(elem,": "));
					} else if (elem.startsWith("Image:")) {
						image=parseElement(elem,": ");
					}
					if (elem.startsWith("ImageLoaded:") && elem.endsWith("dll")) {
						imageLoaded = parseElement(elem,": ");
						LinkedHashSet<EventLogData> evSet;
						if (null == log.get(processId)) {
							evSet=new LinkedHashSet<EventLogData>();
						} else {
							evSet = log.get(processId);
						}
						evSet.add(new EventLogData(date,imageLoaded,image));
						log.put(processId, evSet);
					}

				}
			}
			br.close();

		} catch (IOException e) {
			System.out.println(e);
		}

	}

	private String parseElement(String elem, String delimiter) {
		String value="";
		try{
		String elems[] = elem.split(delimiter);
		value = elems[1].trim();
		}catch (RuntimeException e){
			e.printStackTrace();
		}
		return value;
	}

	private void outputLoadedDLLs(Map map, String outputFileName) {
		File file = new File(outputFileName);
		String filename=file.getName();
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file,true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);

			for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
				Map.Entry<Integer, LinkedHashSet> entry = (Map.Entry<Integer, LinkedHashSet>) it.next();
				Object processId = entry.getKey();
				LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
				LinkedHashSet<String> imageLoadedList = new LinkedHashSet<String>();
				
				for (EventLogData ev: evS) {
					String[] dlls=ev.getImageLoaded().split("\\\\");
					String dllName=dlls[dlls.length-1];
					imageLoadedList.add(dllName);
				}
				boolean result = isMatchWithCommonDLLlist(commonDLLlistFileName, imageLoadedList);
				List<String> list = new ArrayList<String>();
				for (EventLogData ev: evS) {
						String[] dlls=ev.getImageLoaded().split("\\\\");
						String dllName=dlls[dlls.length-1];
						list.add(dllName);
				}
				Collections.reverse(list);
				for (String s: list) {
					pw.print(s + " ");
				}
				String label="normal";
				if(result) {
					label="attack";
				}
				pw.print(", "+label);
				boolean containsMimikatz = false;
				LinkedHashSet<EventLogData> evSet = log.get(processId);
				LinkedHashSet<String> imageList=new LinkedHashSet<String>();
				String image="";
				for (EventLogData ev : evSet) {
					image=ev.getImage();
					if (image.endsWith(MIMIKATZ_MODULE_NAME)) {
						// mimikatz is executed
						containsMimikatz = true;
						imageList.add(image);
						processCntMimi++;
						break;
					}
				}
				pw.println(","+image);
				// Matched with Common DLL List 
				if (result) {
					System.out.println("Detected. filename:"+filename+", Process ID:"+processId);
					detectedProcessCntMimi++;
					if (!containsMimikatz) {
						// mimikatz is not executed
						falsePositiveCnt++;
					}
				} else {
					// Do not matched with Common DLL List 
					if (containsMimikatz) {
						// mimikatz is executed
						/*
						boolean mimiProcessExists=false;
						for(String image : imageList){
							if(image.endsWith(MIMIKATZ_MODULE_NAME)){
								mimiProcessExists=true;
								break;
							}
						}
						*/
						//if(!mimiProcessExists){
						falseNegativeCnt++;
						//}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
	private void outputLoadedDLLsByName(Map map, String outputFileName) {
		File file = new File(outputFileName);
		String filename=file.getName();
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;
		try {
			filewriter = new FileWriter(file,true);
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);

			for (Iterator it = map.entrySet().iterator(); it.hasNext();) {
				Map.Entry<Integer, LinkedHashSet> entry = (Map.Entry<Integer, LinkedHashSet>) it.next();
				Object processId = entry.getKey();
				LinkedHashSet<EventLogData> evS = (LinkedHashSet<EventLogData>) entry.getValue();
				LinkedHashSet<String> imageLoadedList = new LinkedHashSet<String>();
				
				for (EventLogData ev: evS) {
					imageLoadedList.add(ev.getImageLoaded());
					
				}
				List<String> list = new ArrayList<String>();
				for (EventLogData ev: evS) {
						String[] dlls=ev.getImageLoaded().split("\\\\");
						String dllName=dlls[dlls.length-1];
						list.add(dllName);
				}
				Collections.reverse(list);
				for (String s: list) {
					pw.print(s + " ");
				}
				boolean containsMimikatz = false;
				LinkedHashSet<EventLogData> evSet = log.get(processId);
				LinkedHashSet<String> imageList=new LinkedHashSet<String>();
				String image="";
				for (EventLogData ev : evSet) {
					image=ev.getImage();
					if (image.endsWith(MIMIKATZ_MODULE_NAME)) {
						// mimikatz is executed
						containsMimikatz = true;
						imageList.add(image);
						processCntMimi++;
						break;
					}
				}
				String label="normal";
				if(containsMimikatz) {
					label="attack";
				}
				pw.print(", "+label);
				pw.println(","+image);
				 
				if (label.equals("attack")) {
					System.out.println("Detected. filename:"+filename+", Process ID:"+processId);
					detectedProcessCntMimi++;
					if (!containsMimikatz) {
						// mimikatz is not executed
						falsePositiveCnt++;
					}
				} else {
					// Do not matched with Common DLL List 
					if (containsMimikatz) {
						// mimikatz is executed
						/*
						boolean mimiProcessExists=false;
						for(String image : imageList){
							if(image.endsWith(MIMIKATZ_MODULE_NAME)){
								mimiProcessExists=true;
								break;
							}
						}
						*/
						//if(!mimiProcessExists){
						falseNegativeCnt++;
						//}
					}
				}
			}
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private boolean isMatchWithCommonDLLlist(String commonDLLlistFileName, LinkedHashSet<String> imageLoadedList) {
		boolean result = imageLoadedList.containsAll(commonDLLlist);
		return result;
	}

	/**
	* Parse CSV files exported from Sysmon event log.
	* Output process/loaded DLLs and detect which matches Common DLL List.
	* @param inputDirname 
	*/
	public void outputLoadedDlls(String inputDirname) {
		File dir = new File(inputDirname);
		File[] files = dir.listFiles();

		for (File file : files) {
			String filename = file.getName();
			if (filename.endsWith(".csv")) {
				readCSV(file.getAbsolutePath());
				if(detectByExeName) {
					outputLoadedDLLsByName(log, this.outputDirName + "/" + "dlls.csv");
				} else {
					outputLoadedDLLs(log, this.outputDirName + "/" + "dlls.csv");
				}
				totalProcessCnt=totalProcessCnt+=log.size();
				log.clear();
			} else {
				continue;
			}
		}

	}

	/**
	* Evaluate detection rate using Common DLL List.
	*/
	public void outputDetectionRate() {
		FileWriter filewriter = null;
		BufferedWriter bw = null;
		PrintWriter pw = null;

		// mimikatz以外のプロセス数
		int normalProcessCnt =totalProcessCnt-this.processCntMimi;
		
		// mimikatz以外と判定したプロセスの割合
		double trueNegativeRate = (double) (totalProcessCnt-this.detectedProcessCntMimi) / (double)normalProcessCnt;
		// 正しくmimikatzと判定したプロセスの割合
		double truePositiveRate = (double) this.detectedProcessCntMimi / (double)processCntMimi;
		
		// mimikatz以外のプロセスをmimikatzと検知した割合
		double falsePositiveRate = (double) falsePositiveCnt / totalProcessCnt;
		double falseNegativeRate = (double) falseNegativeCnt / this.processCntMimi;
		
		String truePositiveRateS = String.format("%.2f", truePositiveRate);
		String trueNegativeRateS = String.format("%.2f", trueNegativeRate);
		String falsePositiveRateS = String.format("%.2f", falsePositiveRate);
		String falseNegativeRateS = String.format("%.2f", falseNegativeRate);
		try {
			filewriter = new FileWriter(this.outputDirName + "/" + "detectionRate.txt");
			bw = new BufferedWriter(filewriter);
			pw = new PrintWriter(bw);
			pw.println("Total process count: " + totalProcessCnt);
			pw.println("True Positive count: " + this.detectedProcessCntMimi + ", True Positive rate: " + truePositiveRateS);
			pw.println("True Negative count: " + (totalProcessCnt-this.detectedProcessCntMimi) + ", True Negative rate: " + trueNegativeRateS);
			pw.println("False Positive count: " + falsePositiveCnt + ", False Positive rate: " + falsePositiveRateS);
			pw.println("False Negative count: " + falseNegativeCnt + ", False Negative rate: " + falseNegativeRateS);
		} catch (IOException e) {
			e.printStackTrace();
		} finally {
			pw.close();
			try {
				bw.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
		System.out.println("Total process count: " + totalProcessCnt);
		System.out.println("True Positive count: " + this.detectedProcessCntMimi + ", True Positive rate: " + truePositiveRateS);
		System.out.println("True Negative count: " + (totalProcessCnt-this.detectedProcessCntMimi) + ", True Negative rate: " + trueNegativeRateS);
		System.out.println("False Positive count: " + falsePositiveCnt + ", False Positive rate: " + falsePositiveRateS);
		System.out.println("False Negative count: " + falseNegativeCnt + ", False Negative rate: " + falseNegativeRateS);
	}

	private void readCommonDLLList() {
		BufferedReader br = null;
		try {
			File f = new File(commonDLLlistFileName);
			br = new BufferedReader(new FileReader(f));
			String line;
			while ((line = br.readLine()) != null) {
				String dll = line.trim();
				commonDLLlist.add(dll);
			}
		} catch (IOException e) {
			System.out.println(e);
		} finally {
			try {
				br.close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}

	private void detelePrevFiles(String outDirname) {
		Path path = Paths.get(outDirname);
		try (DirectoryStream<Path> ds = Files.newDirectoryStream(path, "*.*")) {
			for (Path deleteFilePath : ds) {
				Files.delete(deleteFilePath);
			}
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private static void printUseage() {
		System.out.println("Useage");
		System.out.println("{iputdirpath} {Common DLL List path} {outputdirpath} (-dr)");
		System.out.println("If you evaluate detection rate using Common DLL Lists specify -dr option.)");
	}

	public static void main(String args[]) {
		SysmonDetecter_ML sysmonParser = new SysmonDetecter_ML();
		String inputdirname="" ;
		if (args.length < 3) {
			printUseage();
		} else if (args.length > 0) {
			inputdirname = args[0];
		}
		if (args.length > 1) {
			commonDLLlistFileName = args[1];
		}
		if (args.length > 2) {
			outputDirName = args[2];
		}
		if (args.length > 4) {
			String option = args[4];
			if (option.equals("-exe")) {
				detectByExeName=true;
			}
		}
		log = new HashMap<Integer, LinkedHashSet>();
		image = new HashMap<Integer, LinkedHashSet>();
		sysmonParser.detelePrevFiles(outputDirName);
		sysmonParser.readCommonDLLList();
		sysmonParser.outputLoadedDlls(inputdirname);
		if (args.length > 3) {
			String option = args[3];
			if (option.equals("-dr")) {
				sysmonParser.outputDetectionRate();
			}
		}
	}

}
